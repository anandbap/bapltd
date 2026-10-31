# BAP Universal Zero-Trust Transactional Launcher Engine
# ========================================================
# Provides the transactional lifecycle engine for all BAP agent launchers:
# - Pre-initializes hooks, MCP configurations, and governance rules.
# - Preserves original developer files transactionally with same-directory backups.
# - Coordinates multi-session concurrency per workspace via Named Mutex & reference counting.
# - Preflights & auto-starts local BAP Control Plane if offline.
# - Enrolls/ends session via bapedge session-start / session-end.
# - Detached background watchdog guards configuration against tampering.
# - Automatic recovery from crashed or stale sessions on launch.
# - Atomically restores original files when the last session exits.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-AtomicText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    $dir = Split-Path -Parent $Path
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $tmp = "$Path.tmp.$PID.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText($tmp, $Text, $Utf8NoBom)
        $retries = 10
        while ($retries -gt 0) {
            try {
                if (Test-Path -LiteralPath $Path) {
                    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
                }
                Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
                break
            }
            catch {
                $retries--
                if ($retries -le 0) {
                    try {
                        [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
                    } catch { }
                    break
                }
                Start-Sleep -Milliseconds 100
            }
        }
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
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $tmp = "$Path.tmp.$PID.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllBytes($tmp, $Bytes)
        $retries = 10
        while ($retries -gt 0) {
            try {
                if (Test-Path -LiteralPath $Path) {
                    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
                }
                Move-Item -LiteralPath $tmp -Destination $Path -Force -ErrorAction Stop
                break
            }
            catch {
                $retries--
                if ($retries -le 0) {
                    try {
                        [System.IO.File]::WriteAllBytes($Path, $Bytes)
                    } catch { }
                    break
                }
                Start-Sleep -Milliseconds 100
            }
        }
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

function Resolve-BinaryPath {
    param(
        [string[]]$Paths,
        [string[]]$Commands
    )
    foreach ($p in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $p).Path
        }
    }
    $isWin = ($env:OS -like "*Windows*") -or ($null -ne (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) -and $IsWindows) -or ([System.Environment]::OSVersion.Platform -match "Win")
    foreach ($name in $Commands) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $tryList = @($name)
        if ($isWin -and -not [System.IO.Path]::HasExtension($name)) {
            $tryList += @("$name.cmd", "$name.bat", "$name.exe")
        }
        foreach ($cand in $tryList) {
            $cmd = Get-Command $cand -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $cmd) {
                if ($cmd.PSObject.Properties.Name -contains 'Source' -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Source)) {
                    return [string]$cmd.Source
                }
                if ($cmd.PSObject.Properties.Name -contains 'Path' -and -not [string]::IsNullOrWhiteSpace([string]$cmd.Path)) {
                    return [string]$cmd.Path
                }
                return $cand
            }
        }
    }
    return $null
}

function Get-WorkspaceMutexName {
    param(
        [Parameter(Mandatory = $true)][string]$Workspace,
        [string]$AgentPrefix = "bap"
    )
    $normalized = [System.IO.Path]::GetFullPath($Workspace).TrimEnd('\').ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        $hash = $sha.ComputeHash($bytes)
        $hex = -join ($hash | ForEach-Object { $_.ToString('x2') })
        return "Local\BAP_${AgentPrefix}_$($hex.Substring(0, 20))"
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
    try { $Mutex.ReleaseMutex() } catch { }
    try { $Mutex.Dispose() } catch { }
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
    Write-JsonAtomic -Path $ManifestPath -Object $Record
    Write-JsonAtomic -Path $mirror -Object $Record
}

function Read-RecoveryRecord {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)
    $mirror = Get-RecoveryMirrorPath -ManifestPath $ManifestPath
    foreach ($candidate in @($ManifestPath, $mirror)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        try {
            return (Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 | ConvertFrom-Json)
        }
        catch { }
    }
    return $null
}

function Test-ProcessIdentity {
    param(
        [int]$ProcessId,
        [int64]$StartTicks
    )
    $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $false }
    try {
        return ($p.StartTime.ToUniversalTime().Ticks -eq $StartTicks)
    }
    catch {
        return $true
    }
}

function Invoke-BapSessionEnd {
    param([Parameter(Mandatory = $true)]$Record)
    try {
        if ($Record.PSObject.Properties.Name -contains 'session_active' -and -not [bool]$Record.session_active) { return }
        $edge = if ($Record.PSObject.Properties.Name -contains 'bapedge_bin') { [string]$Record.bapedge_bin } else { $null }
        $sUrl = if ($Record.PSObject.Properties.Name -contains 'server_url') { [string]$Record.server_url } else { 'http://localhost:8080' }
        $sId = if ($Record.PSObject.Properties.Name -contains 'session_id') { [string]$Record.session_id } else { $null }

        if (-not [string]::IsNullOrWhiteSpace($edge) -and (Test-Path -LiteralPath $edge) -and -not [string]::IsNullOrWhiteSpace($sId)) {
            & $edge session-end --server $sUrl --session-id $sId *> $null
            return
        }

        # Without the broker, retain local recovery state; never send an anonymous teardown.
    }
    catch { }
}

function Restore-TrackedEntry {
    param([Parameter(Mandatory = $true)]$Entry)
    try {
        $path = [string]$Entry.path
        $backup = [string]$Entry.backup
        $existed = [bool]$Entry.existed
        $origHash = [string]$Entry.original_sha256

        if ($existed) {
            if (Test-Path -LiteralPath $backup -PathType Leaf) {
                $retries = 10
                while ($retries -gt 0) {
                    try {
                        if (Test-Path -LiteralPath $path) {
                            try { [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Normal) } catch { }
                            try { [System.IO.File]::Delete($path) } catch { }
                        }
                        try { [System.IO.File]::SetAttributes($backup, [System.IO.FileAttributes]::Normal) } catch { }
                        [System.IO.File]::Copy($backup, $path, $true)
                        try { [System.IO.File]::Delete($backup) } catch { }
                        break
                    }
                    catch {
                        $retries--
                        if ($retries -le 0) {
                            Write-Warning "Could not restore $backup to ${path}: $($_.Exception.Message)"
                            return $false
                        }
                        Start-Sleep -Milliseconds 150
                    }
                }
                return $true
            }
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $curHash = Get-FileSha256 -Path $path
                if ($curHash -eq $origHash) { return $true }
            }
            Write-Warning "Could not prove restoration of original file: $path"
            return $false
        }
        else {
            if (Test-Path -LiteralPath $path) {
                try { [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Normal) } catch { }
                try { [System.IO.File]::Delete($path) } catch { }
            }
            return $true
        }
    }
    catch {
        Write-Warning "Failed restoring entry: $($_.Exception.Message)"
        return $false
    }
}

function Restore-BapSessionState {
    param(
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [string]$Reason = 'cleanup'
    )
    try {
        $record = Read-RecoveryRecord -ManifestPath $ManifestPath
        if ($null -eq $record) { return $true }

        Write-Host "[*] Restoring BAP session transaction ($Reason)..." -ForegroundColor Yellow
        try {
            Invoke-BapSessionEnd -Record $record
        } catch { }

        $allOk = $true
        if ($record.PSObject.Properties.Name -contains 'tracked_files' -and $null -ne $record.tracked_files) {
            foreach ($entry in $record.tracked_files) {
                try {
                    $ok = Restore-TrackedEntry -Entry $entry
                    if (-not $ok) { $allOk = $false }
                }
                catch {
                    Write-Warning "Failed restoring file: $($entry.path): $($_.Exception.Message)"
                    $allOk = $false
                }
            }
        }

        if ($allOk) {
            $mirror = Get-RecoveryMirrorPath -ManifestPath $ManifestPath
            Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $mirror -Force -ErrorAction SilentlyContinue
            Write-Host "[+] All developer configuration files cleanly restored." -ForegroundColor Green
        }
        return $allOk
    }
    catch {
        Write-Warning "Failed restoring session state: $($_.Exception.Message)"
        return $false
    }
}

function Repair-GuardedFiles {
    param([Parameter(Mandatory = $true)]$Record)
    if ($record.PSObject.Properties.Name -contains 'tracked_files' -and $null -ne $record.tracked_files) {
        foreach ($entry in $record.tracked_files) {
            $p = [string]$entry.path
            $expHash = [string]$entry.bap_sha256
            $b64 = [string]$entry.bap_content_b64
            if ([string]::IsNullOrWhiteSpace($b64) -or [string]::IsNullOrWhiteSpace($expHash)) { continue }

            $needsRepair = $false
            if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
                $needsRepair = $true
            } else {
                $cur = Get-FileSha256 -Path $p
                if ($cur -ne $expHash) { $needsRepair = $true }
            }

            if ($needsRepair) {
                $bytes = [Convert]::FromBase64String($b64)
                Write-AtomicBytes -Path $p -Bytes $bytes
            }
        }
    }
}

function Test-TcpPortOpen {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 600)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $client.Connected
    }
    catch { return $false }
    finally { $client.Close() }
}

function Test-ControlPlaneOnline {
    param([string]$Url)
    try {
        $curl = Resolve-BinaryPath -Paths @() -Commands @('curl.exe')
        if ([string]::IsNullOrWhiteSpace($curl)) { return $false }
        $argsList = @('-s', '--max-time', '3', '--connect-timeout', '2')
        if ($Url -like 'https://*') { $argsList += '-k' }
        $argsList += @('-X', 'GET', "$Url/api/v1/health")
        $res = (& $curl @argsList 2>$null | Out-String)
        return ($res -match '(?i)\b(ok|healthy|ltd-service)\b')
    }
    catch { return $false }
}

function Ensure-ControlPlaneRunning {
    param(
        [string]$ServerUrl,
        [string]$RepoRoot
    )
    $uri = [Uri]$ServerUrl
    $isLocal = @('localhost', '127.0.0.1', '::1') -contains $uri.Host

    if ($isLocal) {
        $portOpen = Test-TcpPortOpen -HostName $uri.Host -Port $uri.Port
        if (-not $portOpen) {
            $cpCandidates = @(
                (Join-Path $env:ProgramFiles 'BAP\bin\bapcontrolplane.exe'),
                (Join-Path $env:ProgramFiles 'BAP\bapcontrolplane.exe'),
                (Join-Path $env:USERPROFILE '.bap\bin\bapcontrolplane.exe'),
                (Join-Path $env:USERPROFILE '.bap\bapcontrolplane.exe'),
                (Join-Path $RepoRoot 'dist\windows-amd64\bapcontrolplane.exe'),
                (Join-Path $RepoRoot 'dist\windows-amd64\controlplane\bapcontrolplane.exe'),
                (Join-Path $RepoRoot 'bap-controlplane\bapcontrolplane.exe'),
                (Join-Path $RepoRoot 'bapcontrolplane.exe')
            )
            $cpBin = Resolve-BinaryPath -Paths $cpCandidates -Commands @('bapcontrolplane.exe')
            if (-not [string]::IsNullOrWhiteSpace($cpBin)) {
                Write-Host "[*] Auto-starting local BAP Control Plane on port $($uri.Port)..." -ForegroundColor Yellow
                $cpArgs = @('-port', [string]$uri.Port, '-ttl', '30', '-trust-domain', 'bap.internal')
                if ($uri.Scheme -eq 'https') { $cpArgs += '-https' }
                Start-Process -FilePath $cpBin -ArgumentList $cpArgs -WindowStyle Hidden | Out-Null
                Start-Sleep -Seconds 2
            }
        }
    }

    if (Test-ControlPlaneOnline -Url $ServerUrl) {
        Write-Host "[+] BAP Control Plane verified online ($ServerUrl)." -ForegroundColor Green
    } else {
        Write-Warning "BAP Control Plane ($ServerUrl) did not respond. Local Edge will operate in resilient offline mode."
    }
}

function Start-DetachedWatchdog {
    param(
        [string]$ScriptPath,
        [string]$ManifestPath,
        [string]$MutexName,
        [int]$ParentPid,
        [int64]$ParentTicks
    )
    $psExe = (Get-Process -Id $PID).Path
    $qScript = '"' + $ScriptPath.Replace('"', '""') + '"'
    $qManifest = '"' + $ManifestPath.Replace('"', '""') + '"'
    $qMutex = '"' + $MutexName.Replace('"', '""') + '"'

    $wdArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $qScript,
        '--bap-watchdog',
        '--bap-manifest', $qManifest,
        '--bap-mutex', $qMutex,
        '--bap-parent-pid', [string]$ParentPid,
        '--bap-parent-start-ticks', [string]$ParentTicks
    )

    $p = Start-Process -FilePath $psExe -ArgumentList $wdArgs -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 150
    if ($p.HasExited) {
        throw "Failed to start detached session guard watchdog."
    }
    return $p
}

function Run-WatchdogLoop {
    param(
        [string]$ManifestPath,
        [string]$MutexName,
        [int]$ParentPid,
        [int64]$ParentTicks
    )
    while ($true) {
        $r = Read-RecoveryRecord -ManifestPath $ManifestPath
        if ($null -eq $r) { break }
        if ($r.PSObject.Properties.Name -contains 'state' -and ($r.state -eq 'Cleaning' -or $r.state -eq 'Complete')) {
            break
        }

        $anyAlive = $false
        if ($r.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $r.active_sessions) {
            foreach ($s in $r.active_sessions) {
                $pidVal = [int]($s.launcher_pid)
                if ($pidVal -gt 0) {
                    $pr = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
                    if ($null -ne $pr -and -not $pr.HasExited) {
                        $anyAlive = $true
                        break
                    }
                }
            }
        }
        elseif (Test-ProcessIdentity -ProcessId $ParentPid -StartTicks $ParentTicks) {
            $anyAlive = $true
        }

        if (-not $anyAlive) { break }

        try { Repair-GuardedFiles -Record $r } catch { }
        Start-Sleep -Milliseconds 800
    }

    Start-Sleep -Milliseconds 500
    $wdMutex = Acquire-BapMutex -Name $MutexName -TimeoutMs 15000
    if ($null -eq $wdMutex) { exit 94 }
    try {
        if ((Test-Path -LiteralPath $ManifestPath) -or (Test-Path -LiteralPath (Get-RecoveryMirrorPath -ManifestPath $ManifestPath))) {
            $r = Read-RecoveryRecord -ManifestPath $ManifestPath
            $stillAlive = $false
            if ($null -ne $r -and $r.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $r.active_sessions) {
                foreach ($s in $r.active_sessions) {
                    $pId = [int]($s.launcher_pid)
                    if ($pId -gt 0) {
                        $pr = Get-Process -Id $pId -ErrorAction SilentlyContinue
                        if ($null -ne $pr -and -not $pr.HasExited) { $stillAlive = $true; break }
                    }
                }
            }
            if (-not $stillAlive) {
                [void](Restore-BapSessionState -ManifestPath $ManifestPath -Reason 'all launcher sessions terminated')
            }
        }
    }
    finally {
        Release-BapMutex -Mutex $wdMutex
    }
    exit 0
}

# -----------------------------------------------------------------------------
# Layer 3: Tool Call & Terminal Interceptor Shims
# -----------------------------------------------------------------------------
function Initialize-BapShims {
    param(
        [Parameter(Mandatory = $true)][string]$Workspace,
        [Parameter(Mandatory = $true)][string]$BapEdgeBin,
        [Parameter(Mandatory = $true)][string]$AgentId,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    $shimDir = Join-Path $Workspace ".bapstate\shims-$SessionId"
    if (-not (Test-Path -LiteralPath $shimDir)) {
        New-Item -ItemType Directory -Path $shimDir -Force | Out-Null
    }

    $toolsToShim = @('git', 'python', 'curl', 'wget', 'powershell', 'cat', 'rm')
    foreach ($tool in $toolsToShim) {
        $realBin = $null
        try {
            $cmdObj = Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $cmdObj -and -not [string]::IsNullOrWhiteSpace($cmdObj.Source)) {
                $realBin = $cmdObj.Source
            }
        } catch { }

        if ([string]::IsNullOrWhiteSpace($realBin)) {
            if ($tool -eq 'git') { $realBin = 'C:\Program Files\Git\cmd\git.exe' }
            elseif ($tool -eq 'curl') { $realBin = 'C:\Windows\System32\curl.exe' }
            elseif ($tool -eq 'powershell') { $realBin = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
            elseif ($tool -eq 'cat') { $realBin = 'C:\Program Files\Git\usr\bin\cat.exe' }
            elseif ($tool -eq 'rm') { $realBin = 'C:\Program Files\Git\usr\bin\rm.exe' }
            elseif ($tool -eq 'python') { $realBin = 'python.exe' }
        }

        $shimContent = @"
@echo off
if "%BAP_IN_BROKER%"=="1" goto REAL_RUN
"$BapEdgeBin" exec --source %LTD_SOURCE% --session-id %BAP_SESSION_ID% --raw "%~n0 %*"
exit /b %ERRORLEVEL%

:REAL_RUN
"$realBin" %*
exit /b %ERRORLEVEL%
"@

        $shimFile = Join-Path $shimDir "$tool.cmd"
        [System.IO.File]::WriteAllText($shimFile, $shimContent, [System.Text.UTF8Encoding]::new($false))
    }

    return $shimDir
}

function Initialize-CorporateMirrors {
    param(
        [Parameter(Mandatory = $true)][string]$Workspace,
        [Parameter(Mandatory = $true)][string]$SessionId
    )

    $mirrorDir = Join-Path $Workspace ".bapstate\mirrors"
    if (-not (Test-Path -LiteralPath $mirrorDir)) {
        New-Item -ItemType Directory -Path $mirrorDir -Force | Out-Null
    }

    $nexusBase = if ($env:BAP_NEXUS_URL) { $env:BAP_NEXUS_URL.TrimEnd('/') } else { "http://nexus.corp.internal" }
    $mavenMirrorUrl = "$nexusBase/repository/maven-public/"
    $npmMirrorUrl = "$nexusBase/repository/npm-group/"
    $pypiMirrorUrl = "$nexusBase/repository/pypi-group/simple"
    $nexusHost = "nexus.corp.internal"
    try {
        $uri = [System.Uri]$nexusBase
        if ($null -ne $uri -and -not [string]::IsNullOrWhiteSpace($uri.Host)) {
            $nexusHost = $uri.Host
        }
    } catch { }

    # 1. Maven settings.xml
    $settingsXmlPath = Join-Path $mirrorDir "settings.xml"
    $settingsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.2.0 http://maven.apache.org/xsd/settings-1.2.0.xsd">
  <mirrors>
    <mirror>
      <id>bap-corporate-nexus</id>
      <name>Corporate Nexus Repository Mirror</name>
      <url>$mavenMirrorUrl</url>
      <mirrorOf>central,*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
"@
    Write-AtomicText -Path $settingsXmlPath -Text $settingsContent

    # 2. npm .npmrc
    $npmrcPath = Join-Path $mirrorDir ".npmrc"
    $npmrcContent = @"
registry=$npmMirrorUrl
strict-ssl=true
audit=false
"@
    Write-AtomicText -Path $npmrcPath -Text $npmrcContent

    # 3. pip pip.ini
    $pipIniPath = Join-Path $mirrorDir "pip.ini"
    $pipContent = @"
[global]
index-url = $pypiMirrorUrl
trusted-host = $nexusHost
timeout = 15
"@
    Write-AtomicText -Path $pipIniPath -Text $pipContent

    # Inject into process environment
    $env:MAVEN_ARGS = "-s `"$settingsXmlPath`""
    $env:M2_SETTINGS_XML = $settingsXmlPath
    $env:NPM_CONFIG_USERCONFIG = $npmrcPath
    $env:NPM_CONFIG_REGISTRY = $npmMirrorUrl
    $env:PIP_CONFIG_FILE = $pipIniPath
    $env:PIP_INDEX_URL = $pypiMirrorUrl

    Write-Host "[+] Supply-Chain Defense: Corporate mirror configurations injected (Nexus: Maven, npm, pip)." -ForegroundColor Green
    return $mirrorDir
}

# -----------------------------------------------------------------------------
# Main Universal Transactional Execution Broker
# -----------------------------------------------------------------------------
function Invoke-BapGovernedSession {
    param(
        [Parameter(Mandatory = $true)][string]$AgentId,        # 'claude-code', 'copilot', 'antigravity'
        [Parameter(Mandatory = $true)][string]$AgentMode,      # 'cli' or 'ide'
        [Parameter(Mandatory = $true)][string]$DisplayName,    # e.g. "GitHub Copilot (VS Code IDE Mode)"
        [Parameter(Mandatory = $true)][string[]]$CandidateExecutables,
        [Parameter(Mandatory = $true)][scriptblock]$ConfigureFiles, # callback: ($Workspace, $SessionId) -> @( @{ Path; Content } )
        [string[]]$ScriptRawArgs = @(),
        [string]$CallingScript = $PSCommandPath
    )

    # 1. Parse Launcher/Watchdog mode
    $Mode = 'Launcher'
    $ServerUrl = $null
    $BapEdgeBin = $null
    $ServerExplicit = $false
    $ManifestArg = $null
    $MutexArg = $null
    $ParentPidArg = 0
    $ParentTicksArg = [int64]0
    $UserPrompt = $env:BAP_USER_PROMPT
    $ForwardArgs = @()

    for ($i = 0; $i -lt $ScriptRawArgs.Count; $i++) {
        $a = [string]$ScriptRawArgs[$i]
        if ($a -eq '--bap-watchdog') { $Mode = 'Watchdog'; continue }
        if ($a -eq '--bap-manifest') { $i++; $ManifestArg = [string]$ScriptRawArgs[$i]; continue }
        if ($a -eq '--bap-mutex') { $i++; $MutexArg = [string]$ScriptRawArgs[$i]; continue }
        if ($a -eq '--bap-parent-pid') { $i++; $ParentPidArg = [int]$ScriptRawArgs[$i]; continue }
        if ($a -eq '--bap-parent-start-ticks') { $i++; $ParentTicksArg = [int64]$ScriptRawArgs[$i]; continue }
        if ($a -eq '--server' -or $a -eq '-ServerUrl') { $i++; $ServerUrl = [string]$ScriptRawArgs[$i]; $ServerExplicit = $true; continue }
        if ($a -like '--server=*') { $ServerUrl = $a.Substring('--server='.Length); $ServerExplicit = $true; continue }
        if ($a -eq '--prompt' -or $a -eq '-p' -or $a -eq '-Prompt') {
            if (($i + 1) -lt $ScriptRawArgs.Count) {
                $UserPrompt = [string]$ScriptRawArgs[$i + 1]
            }
        }
        if ($a -like '--prompt=*') { $UserPrompt = $a.Substring('--prompt='.Length) }
        if ($a -like '-p=*') { $UserPrompt = $a.Substring('-p='.Length) }
        $ForwardArgs += $a
    }

    # Metadata inspection must not create a workload, watchdog, or control plane.
    if ($Mode -eq 'Launcher' -and $AgentMode -eq 'cli' -and $ForwardArgs.Count -eq 1 -and $ForwardArgs[0] -eq '--version') {
        Write-Host "BOUNDED AUTHORITY PLANE (BAP) - $DisplayName ($AgentId)"
        foreach ($candidate in $CandidateExecutables) {
            $versionCommand = Get-Command $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $versionCommand) {
                & $candidate --version
                if ($null -eq $LASTEXITCODE) { exit 0 }
                exit $LASTEXITCODE
            }
        }
        throw "Executable for $DisplayName was not found."
    }

    # Watchdog child execution
    if ($Mode -eq 'Watchdog') {
        Run-WatchdogLoop -ManifestPath $ManifestArg -MutexName $MutexArg -ParentPid $ParentPidArg -ParentTicks $ParentTicksArg
        exit 0
    }

    # 2. Setup Workspace Context
    $Workspace = [System.IO.Path]::GetFullPath((Get-Location).Path)
    $RepoRoot = $Workspace
    $ScriptDir = Split-Path -Parent $CallingScript
    if (Test-Path (Join-Path $ScriptDir 'bap-controlplane')) {
        $RepoRoot = $ScriptDir
    } elseif (Test-Path (Join-Path (Split-Path -Parent $ScriptDir) 'bap-controlplane')) {
        $RepoRoot = Split-Path -Parent $ScriptDir
    }

    $BapStateDir = Join-Path $Workspace '.bapstate'
    if (-not (Test-Path -LiteralPath $BapStateDir)) {
        New-Item -ItemType Directory -Path $BapStateDir -Force | Out-Null
    }

    $ManifestPath = Join-Path $BapStateDir "recovery-$AgentId-$AgentMode.json"
    $MirrorPath = Get-RecoveryMirrorPath -ManifestPath $ManifestPath
    $MutexName = Get-WorkspaceMutexName -Workspace $Workspace -AgentPrefix "$AgentId-$AgentMode"
    $SessionId = "sess-$AgentId-$AgentMode-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"

    $parentProc = Get-Process -Id $PID
    $ParentTicks = $parentProc.StartTime.ToUniversalTime().Ticks
    $PowerShellExe = $parentProc.Path

    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        $ServerUrl = $env:BAP_SERVER_URL
    }
    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        $ServerUrl = 'http://localhost:8080'
    }
    $ServerUrl = $ServerUrl.TrimEnd('/')

    $isSecondary = $false
    $RecoveryRecord = $null
    $ExitCode = 0
    $transcriptJob = $null
    $scrubbedVars = @{}
    $origPath = $null
    $ShimDir = $null

    try {
        try {
            $Host.UI.RawUI.WindowTitle = "$DisplayName (Governed by BAP Zero-Trust)"
        } catch { }

        Write-Host "===============================================================================" -ForegroundColor Cyan
        Write-Host "  BOUNDED AUTHORITY PLANE (BAP) - ZERO-TRUST LAUNCHER: $DisplayName" -ForegroundColor Cyan
        Write-Host "===============================================================================" -ForegroundColor Cyan
        Write-Host "[*] Workspace Target : $Workspace"
        Write-Host "[*] Active Session ID: $SessionId"
        Write-Host "[*] Identity Agent   : $AgentId (Mode: $AgentMode)"
        Write-Host ""

        # 3. Coordinate Multi-Session Custody via Mutex
        $coordMutex = Acquire-BapMutex -Name $MutexName -TimeoutMs 5000
        if ($null -eq $coordMutex) {
            throw "Could not acquire workspace coordination lock ($MutexName) within 5 seconds."
        }

        try {
            if ((Test-Path -LiteralPath $ManifestPath) -or (Test-Path -LiteralPath $MirrorPath)) {
                $existing = Read-RecoveryRecord -ManifestPath $ManifestPath
                if ($null -ne $existing) {
                    $surviving = @()
                    if ($existing.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $existing.active_sessions) {
                        foreach ($s in $existing.active_sessions) {
                            $spid = [int]($s.launcher_pid)
                            if ($spid -gt 0) {
                                $pr = Get-Process -Id $spid -ErrorAction SilentlyContinue
                                if ($null -ne $pr -and -not $pr.HasExited) { $surviving += $s }
                            }
                        }
                    }

                    if ($surviving.Count -gt 0) {
                        # Join active workspace session group
                        $isSecondary = $true
                        $existing.active_sessions = @($surviving) + @([ordered]@{
                            launcher_pid         = [int]$PID
                            launcher_start_ticks = [int64]$ParentTicks
                            session_id           = [string]$SessionId
                            agent_id             = [string]$AgentId
                            mode                 = [string]$AgentMode
                        })
                        $existing.state = 'Active'
                        Write-RecoveryRecord -Record $existing -ManifestPath $ManifestPath
                        $RecoveryRecord = $existing
                        Write-Host "[+] Joined active BAP-governed workspace ($($existing.active_sessions.Count) active sessions)." -ForegroundColor Green
                    } else {
                        Write-Host "[!] Stale session detected from prior crash. Running recovery..." -ForegroundColor Yellow
                        [void](Restore-BapSessionState -ManifestPath $ManifestPath -Reason 'stale session cleanup')
                    }
                }
            }
        }
        finally {
            Release-BapMutex -Mutex $coordMutex
        }

        # 4. Preflight Control Plane
        Ensure-ControlPlaneRunning -ServerUrl $ServerUrl -RepoRoot $RepoRoot

        # 5. Resolve Edge Daemon and Interceptor
        $edgeCandidates = @(
            (Join-Path $env:ProgramFiles 'BAP\bin\bapedge.exe'),
            (Join-Path $env:ProgramFiles 'BAP\bapedge.exe'),
            (Join-Path $env:USERPROFILE '.bap\bin\bapedge.exe'),
            (Join-Path $env:USERPROFILE '.bap\bapedge.exe'),
            (Join-Path $RepoRoot 'dist\windows-amd64\bapedge.exe'),
            (Join-Path $RepoRoot 'bap-edge\bapedge.exe'),
            (Join-Path $RepoRoot 'bapedge.exe')
        )
        $BapEdgeBin = Resolve-BinaryPath -Paths $edgeCandidates -Commands @('bapedge.exe')

        # 6. Resolve Target Executable
        $TargetBin = Resolve-BinaryPath -Paths $CandidateExecutables -Commands $CandidateExecutables
        if ([string]::IsNullOrWhiteSpace($TargetBin)) {
            throw "Target executable for $DisplayName not found. Looked for: $($CandidateExecutables -join ', ')"
        }
        Write-Host "[+] Target Executable: $TargetBin" -ForegroundColor Gray

        # 7. Take Transactional Custody of Configuration Files (Primary Session)
        if (-not $isSecondary) {
            $filesSpec = & $ConfigureFiles $Workspace $SessionId
            $trackedList = @()

            foreach ($spec in $filesSpec) {
                $targetFile = [string]$spec.Path
                $bapContent = [string]$spec.Content
                $fDir = Split-Path -Parent $targetFile
                if (-not [string]::IsNullOrWhiteSpace($fDir) -and -not (Test-Path -LiteralPath $fDir)) {
                    New-Item -ItemType Directory -Path $fDir -Force | Out-Null
                }

                $existed = Test-Path -LiteralPath $targetFile -PathType Leaf
                $backupPath = "$targetFile.bap-backup-$SessionId"
                $origSha = if ($existed) { Get-FileSha256 -Path $targetFile } else { $null }

                if ($existed) {
                    Move-Item -LiteralPath $targetFile -Destination $backupPath -Force
                }

                # Write BAP governed content
                Write-AtomicText -Path $targetFile -Text $bapContent
                $bapSha = Get-FileSha256 -Path $targetFile
                $bapBytes = [System.IO.File]::ReadAllBytes($targetFile)

                $trackedList += [ordered]@{
                    path             = $targetFile
                    existed          = [bool]$existed
                    backup           = $backupPath
                    original_sha256  = $origSha
                    bap_sha256       = $bapSha
                    bap_content_b64  = [Convert]::ToBase64String($bapBytes)
                }
            }

            $RecoveryRecord = [ordered]@{
                version              = 2
                session_id           = $SessionId
                agent_id             = $AgentId
                agent_mode           = $AgentMode
                state                = 'Prepared'
                workspace            = $Workspace
                launcher_pid         = [int]$PID
                launcher_start_ticks = [int64]$ParentTicks
                watchdog_pid         = 0
                server_url           = $ServerUrl
                bapedge_bin          = $BapEdgeBin
                session_active       = $false
                created_utc          = [DateTime]::UtcNow.ToString('o')
                active_sessions      = @(
                    [ordered]@{
                        launcher_pid         = [int]$PID
                        launcher_start_ticks = [int64]$ParentTicks
                        session_id           = [string]$SessionId
                        agent_id             = [string]$AgentId
                        mode                 = [string]$AgentMode
                    }
                )
                tracked_files        = $trackedList
            }

            Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath

            # Start detached session guard
            $watchdog = Start-DetachedWatchdog -ScriptPath $CallingScript -ManifestPath $ManifestPath -MutexName $MutexName -ParentPid $PID -ParentTicks $ParentTicks
            $RecoveryRecord.watchdog_pid = [int]$watchdog.Id
            $RecoveryRecord.state = 'Guarded'
            Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath
            Write-Host "[+] Detached session guard active (PID $($watchdog.Id))." -ForegroundColor Green
        }

        # 8. Enroll BAP Session with Local Edge / Control Plane
        $env:BAP_SESSION_ID = $SessionId
        $env:BAP_SERVER_URL = $ServerUrl
        $env:LTD_SOURCE = $AgentId
        if (-not [string]::IsNullOrWhiteSpace($UserPrompt)) {
            $env:BAP_USER_PROMPT = $UserPrompt
        }

        if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin)) {
            Write-Host "[*] Enrolling session '$SessionId' with BAP Edge..." -ForegroundColor Cyan
            $startParams = @("session-start", "--server", $ServerUrl, "--session-id", $SessionId, "--app-id", $AgentId)
            if (-not [string]::IsNullOrWhiteSpace($UserPrompt)) {
                $startParams += @("--prompt", $UserPrompt)
            }
            & $BapEdgeBin @startParams
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] Session enrolled successfully in BAP Live Radar!" -ForegroundColor Green
            } else {
                Write-Warning "bapedge session-start returned $LASTEXITCODE. Continuing under local zero-trust policy."
            }
        }

        # Transmit prompt telemetry so it immediately surfaces on Dashboard Live Radar & Timeline
        if (-not [string]::IsNullOrWhiteSpace($UserPrompt) -and -not [string]::IsNullOrWhiteSpace($ServerUrl)) {
            try {
                $shaBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($UserPrompt))
                $pHash = -join ($shaBytes | ForEach-Object { $_.ToString('x2') })
                $promptPayload = @{
                    session_id             = $SessionId
                    user_prompt            = $UserPrompt
                    producer               = "bap-agent"
                    prompt_hash            = $pHash
                    prompt_capture_enabled = $true
                    intent                 = @{
                        primary            = "INVESTIGATION"
                        secondary          = @()
                        tags               = @()
                        confidence         = 0.90
                        classifier_version = "bap-edge-rules-v1"
                        source             = "bap-agent"
                    }
                } | ConvertTo-Json -Compress

                if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin)) {
                    $promptPayload | & $BapEdgeBin session-telemetry --server $ServerUrl --kind prompt *> $null
                }
            } catch { }
        }

        if ($null -ne $RecoveryRecord) {
            $RecoveryRecord.session_active = $true
            $RecoveryRecord.state = 'Running'
            Write-RecoveryRecord -Record $RecoveryRecord -ManifestPath $ManifestPath
        }

        # 8B. Layer 3: Setup Tool Call & Terminal Interceptor Shims
        $ShimDir = $null
        $origPath = $env:PATH
        if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin)) {
            $ShimDir = Initialize-BapShims -Workspace $Workspace -BapEdgeBin $BapEdgeBin -AgentId $AgentId -SessionId $SessionId
            $env:PATH = "$ShimDir;$origPath"
            Write-Host "[+] Layer 3 shims active in $ShimDir (git, python, curl, powershell, cat)." -ForegroundColor Gray
        }

        # 8C. Supply-Chain Governance: Inject Corporate Mirrors (Nexus / Artifactory)
        $MirrorDir = Initialize-CorporateMirrors -Workspace $Workspace -SessionId $SessionId

        # 8D. Layer 4: Setup Runtime Execution Broker & Environment
        $env:BAP_MODE = "enforce"
        $env:BAP_AGENT_SANDBOX = "1"
        $env:BAP_IN_BROKER = "0"

        # Scrub ambient sensitive credentials from agent process scope (BAP-535)
        $sensitiveVarPatterns = @(
            'AWS_SECRET*', 'AWS_SESSION*', 'AWS_SECURITY*',
            'GITHUB_TOKEN', 'GH_TOKEN', 'OPENAI_API*', 'ANTHROPIC_API*',
            'SLACK_TOKEN', 'SLACK_BOT*', 'AZURE_CLIENT_SECRET',
            'GOOGLE_APPLICATION_CREDENTIALS', 'NPM_TOKEN', 'PYPI_PASSWORD',
            '*_SECRET', '*_SECRET_KEY', '*_PRIVATE_KEY', '*_AUTH_TOKEN'
        )
        foreach ($pattern in $sensitiveVarPatterns) {
            Get-ChildItem "env:$pattern" -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -notmatch '^(BAP_|LTD_|CORP_)') {
                    $scrubbedVars[$_.Name] = $_.Value
                    Remove-Item "env:$($_.Name)" -ErrorAction SilentlyContinue
                }
            }
        }

        # Start detached watcher to monitor agent process tree and sync heartbeats/revocations
        if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin) -and -not [string]::IsNullOrWhiteSpace($ServerUrl)) {
            try {
                Start-Process -FilePath $BapEdgeBin -ArgumentList @("watch", "--pid", "$PID", "--server", $ServerUrl, "--session-id", $SessionId, "--app-id", $AgentId, "--detach") -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            } catch { }
        }

        # For Antigravity sessions, start background prompt tail to capture prompts typed interactively
        $transcriptJob = $null
        if ($AgentId -eq 'antigravity' -and -not [string]::IsNullOrWhiteSpace($ServerUrl)) {
            $transcriptJob = Start-Job -ScriptBlock {
                param($SessionId, $ServerUrl, $BapEdgeBin)
                $searchRoots = @(
                    (Join-Path $env:USERPROFILE ".gemini\antigravity-cli\brain"),
                    (Join-Path $env:USERPROFILE ".gemini\antigravity\brain")
                )
                $seenHashes = @{}
                $sha = [System.Security.Cryptography.SHA256]::Create()
                while ($true) {
                    Start-Sleep -Milliseconds 800
                    try {
                        foreach ($root in $searchRoots) {
                            if (Test-Path -LiteralPath $root) {
                                $recentFiles = @(
                                    (Get-ChildItem -Path "$root\*\.system_generated\logs\transcript.jsonl" -ErrorAction SilentlyContinue),
                                    (Get-ChildItem -Path "$root\*\transcript.jsonl" -ErrorAction SilentlyContinue)
                                ) | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } |
                                    Sort-Object LastWriteTime -Descending | Select-Object -First 3
                                foreach ($f in $recentFiles) {
                                    $lines = Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue | Select-Object -Last 10
                                    foreach ($l in $lines) {
                                        $userReq = $null
                                        if ($l -match '<USER_REQUEST>([\s\S]*?)</USER_REQUEST>') {
                                            $userReq = $matches[1].Trim()
                                        } elseif ($l -match '"type"\s*:\s*"USER_INPUT"') {
                                            try {
                                                $jsonObj = $l | ConvertFrom-Json -ErrorAction SilentlyContinue
                                                if ($null -ne $jsonObj -and -not [string]::IsNullOrWhiteSpace($jsonObj.content)) {
                                                    $rawContent = $jsonObj.content
                                                    if ($rawContent -match '<USER_REQUEST>([\s\S]*?)</USER_REQUEST>') {
                                                        $userReq = $matches[1].Trim()
                                                    } else {
                                                        $stripped = $rawContent -replace '(?s)<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>', ''
                                                        $stripped = $stripped -replace '(?s)<USER_SETTINGS_CHANGE>.*?</USER_SETTINGS_CHANGE>', ''
                                                        $userReq = $stripped.Trim()
                                                    }
                                                }
                                            } catch { }
                                        }

                                        if (-not [string]::IsNullOrWhiteSpace($userReq)) {
                                            $bytes = [System.Text.Encoding]::UTF8.GetBytes($userReq)
                                            $pHash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
                                            if (-not $seenHashes.ContainsKey($pHash)) {
                                                $seenHashes[$pHash] = $true
                                                $payload = @{
                                                    session_id             = $SessionId
                                                    user_prompt            = $userReq
                                                    producer               = "antigravity-cli"
                                                    prompt_hash            = $pHash
                                                    prompt_capture_enabled = $true
                                                    intent                 = @{
                                                        primary            = "INVESTIGATION"
                                                        confidence         = 0.90
                                                        classifier_version = "bap-edge-rules-v1"
                                                        source             = "antigravity-transcript-tail"
                                                    }
                                                } | ConvertTo-Json -Compress
                                                $curl = 'curl.exe'
                                                $payload | & $BapEdgeBin session-telemetry --server $ServerUrl --kind prompt *> $null
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch { }
                }
            } -ArgumentList $SessionId, $ServerUrl, $BapEdgeBin
        }

        # For Copilot sessions, start background tail to capture prompts, outputs, and token usage
        if ($AgentId -eq 'copilot' -and -not [string]::IsNullOrWhiteSpace($ServerUrl)) {
            $transcriptJob = Start-Job -ScriptBlock {
                param($SessionId, $ServerUrl, $BapEdgeBin)
                $copilotDir = Join-Path $env:USERPROFILE ".copilot\session-state"
                $seenHashes = @{}
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $curl = 'curl.exe'

                while ($true) {
                    Start-Sleep -Milliseconds 800
                    try {
                        if (Test-Path -LiteralPath $copilotDir) {
                            $recentFile = Get-ChildItem -Path "$copilotDir\*\events.jsonl" -ErrorAction SilentlyContinue |
                                Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } |
                                Sort-Object LastWriteTime -Descending | Select-Object -First 1

                            if ($null -ne $recentFile) {
                                $lines = Get-Content -LiteralPath $recentFile.FullName -ErrorAction SilentlyContinue | Select-Object -Last 25
                                foreach ($l in $lines) {
                                    if ([string]::IsNullOrWhiteSpace($l)) { continue }
                                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($l)
                                    $lHash = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
                                    if ($seenHashes.ContainsKey($lHash)) { continue }
                                    $seenHashes[$lHash] = $true

                                    try {
                                        $ev = $l | ConvertFrom-Json -ErrorAction SilentlyContinue
                                        if ($null -eq $ev -or [string]::IsNullOrWhiteSpace($ev.type)) { continue }

                                        # 1. User Prompt Capture
                                        if ($ev.type -eq "user.message" -and $null -ne $ev.data) {
                                            $promptText = [string]$ev.data.content
                                            if ([string]::IsNullOrWhiteSpace($promptText)) {
                                                $promptText = [string]$ev.data.transformedContent
                                            }
                                            if (-not [string]::IsNullOrWhiteSpace($promptText)) {
                                                $pBytes = [System.Text.Encoding]::UTF8.GetBytes($promptText)
                                                $pHash = -join ($sha.ComputeHash($pBytes) | ForEach-Object { $_.ToString('x2') })
                                                $promptPayload = @{
                                                    session_id             = $SessionId
                                                    user_prompt            = $promptText
                                                    producer               = "copilot-cli"
                                                    prompt_hash            = $pHash
                                                    prompt_capture_enabled = $true
                                                    intent                 = @{
                                                        primary            = "INVESTIGATION"
                                                        confidence         = 0.90
                                                        classifier_version = "bap-edge-rules-v1"
                                                        source             = "copilot-events-tail"
                                                    }
                                                } | ConvertTo-Json -Compress
                                                $promptPayload | & $BapEdgeBin session-telemetry --server $ServerUrl --kind prompt *> $null
                                            }
                                        }

                                        # 2. Assistant Response Output Capture
                                        if ($ev.type -eq "assistant.message" -and $null -ne $ev.data -and -not [string]::IsNullOrWhiteSpace($ev.data.content)) {
                                            $outContent = [string]$ev.data.content
                                            $summary = if ($outContent.Length -gt 250) { $outContent.Substring(0, 247) + "..." } else { $outContent }
                                            $auditPayload = @{
                                                event_id     = "ev-copilot-out-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
                                                session_id   = $SessionId
                                                source       = "copilot"
                                                executable   = "assistant_response"
                                                arguments    = "Turn: $($ev.data.turnId)"
                                                full_command = $summary
                                                decision     = "allow"
                                                reason       = "Copilot Assistant Response Output"
                                                timestamp    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                                            } | ConvertTo-Json -Compress
                                            $cArgs = @('-s', '--max-time', '2', '-X', 'POST', "$ServerUrl/api/v1/audit/ingest", '-H', 'Content-Type: application/json', '-d', $auditPayload)
                                            & $curl @cArgs *> $null
                                        }

                                        # 3. Intermediate Token Accounting
                                        if ($ev.type -eq "session.usage_record" -and $null -ne $ev.data) {
                                            $usageObj = $ev.data
                                            $inT = if ($usageObj.inputTokens) { $usageObj.inputTokens } else { $usageObj.tokenDetails.input.tokenCount }
                                            $outT = if ($usageObj.outputTokens) { $usageObj.outputTokens } else { $usageObj.tokenDetails.output.tokenCount }
                                            $credits = if ($usageObj.totalNanoAiu) { [Math]::Round([double]$usageObj.totalNanoAiu / 1000000000, 4) } else { 0 }
                                            $modelName = if ($ev.data.currentModel) { $ev.data.currentModel } else { "copilot" }

                                            $tokenAudit = @{
                                                event_id     = "ev-copilot-tokens-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
                                                session_id   = $SessionId
                                                source       = "copilot"
                                                executable   = "token_accounting"
                                                arguments    = "In: $inT, Out: $outT, Credits: $credits"
                                                full_command = "Copilot $modelName Turn Usage (In: $inT, Out: $outT, Credits: $credits)"
                                                decision     = "allow"
                                                reason       = "Copilot Turn Token Accounting"
                                                timestamp    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                                            } | ConvertTo-Json -Compress
                                            $cArgs = @('-s', '--max-time', '2', '-X', 'POST', "$ServerUrl/api/v1/audit/ingest", '-H', 'Content-Type: application/json', '-d', $tokenAudit)
                                            & $curl @cArgs *> $null
                                        }
                                    } catch { }
                                }
                            }
                        }
                    } catch { }
                }
            } -ArgumentList $SessionId, $ServerUrl, $BapEdgeBin
        }

        # 9. Launch Target Process
        Write-Host ""
        Write-Host "===============================================================================" -ForegroundColor Green
        Write-Host "  $DisplayName IS NOW GOVERNED BY BAP ZERO-TRUST" -ForegroundColor Green
        Write-Host "===============================================================================" -ForegroundColor Green
        Write-Host ""

        if ($AgentMode -eq 'ide') {
            $ideArgs = @()
            if ($ForwardArgs.Count -gt 0) {
                $ideArgs += $ForwardArgs
            } else {
                $ideArgs += $Workspace
            }

            Write-Host "[*] Launching $DisplayName for workspace: $Workspace" -ForegroundColor Cyan
            $targetProc = Start-Process -FilePath $TargetBin -ArgumentList $ideArgs -PassThru -ErrorAction SilentlyContinue

            Write-Host "[+] BAP Governed Session '$SessionId' is ACTIVE." -ForegroundColor Green
            Write-Host "[+] BAP Control Plane : $ServerUrl" -ForegroundColor Cyan
            Write-Host "[+] Zero-Trust Guard  : Monitoring IDE processes & live transcripts..." -ForegroundColor Green
            Write-Host "[*] Keep this console window open while working in the IDE." -ForegroundColor Yellow
            Write-Host "[*] Press 'q' or Enter in this window to end the session (or close the IDE)." -ForegroundColor Yellow
            Write-Host ""

            $procName = [System.IO.Path]::GetFileNameWithoutExtension($TargetBin)
            Start-Sleep -Seconds 2

            while ($true) {
                try {
                    if (-not [Console]::IsInputRedirected -and [Console]::KeyAvailable) {
                        $key = [Console]::ReadKey($true)
                        if ($key.Key -eq [ConsoleKey]::Enter -or $key.Key -eq [ConsoleKey]::Q -or $key.Key -eq [ConsoleKey]::Escape) {
                            Write-Host "`n[*] Ending BAP session as requested..." -ForegroundColor Yellow
                            break
                        }
                    }
                } catch { }

                $aliveProcs = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($null -eq $aliveProcs -or $aliveProcs.Count -eq 0) {
                    Write-Host "`n[*] All $DisplayName processes exited. Ending BAP session..." -ForegroundColor Gray
                    break
                }

                Start-Sleep -Milliseconds 800
            }
            $ExitCode = 0
        } else {
            $cliExecArgs = @($ForwardArgs)
            if ($AgentId -eq 'copilot' -and ($TargetBin -like '*gh.exe' -or $TargetBin -like '*\gh') -and ($cliExecArgs.Count -eq 0 -or $cliExecArgs[0] -ne 'copilot')) {
                $cliExecArgs = @('copilot') + $cliExecArgs
            }
            $cancelHandler = $null
            try {
                $cancelHandler = [ConsoleCancelEventHandler]{
                    param($sender, $eventArgs)
                    # Intercept Ctrl+C so child process receives signal and terminates,
                    # while parent PowerShell script remains alive to execute finally cleanup.
                    $eventArgs.Cancel = $true
                }
                [Console]::add_CancelKeyPress($cancelHandler)
            } catch { }

            try {
                & $TargetBin @cliExecArgs
                $pExit = $LASTEXITCODE
                $ExitCode = if ($null -eq $pExit) { 0 } else { [int]$pExit }
                Write-Host "[*] $DisplayName exited with code $ExitCode." -ForegroundColor Gray
            } finally {
                if ($null -ne $cancelHandler) {
                    try { [Console]::remove_CancelKeyPress($cancelHandler) } catch { }
                }
            }
        }
    }
    catch {
        if ($ExitCode -eq 0) { $ExitCode = 1 }
        Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        # 10. Multi-Session Teardown Coordination
        Write-Host "`n[*] Performing BAP session teardown for session '$SessionId'..." -ForegroundColor Yellow

        if ($null -ne $transcriptJob) {
            Stop-Job $transcriptJob -ErrorAction SilentlyContinue | Out-Null
            Remove-Job $transcriptJob -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # For Copilot sessions, capture final accounting snapshot & token usage
        if ($AgentId -eq 'copilot') {
            try {
                $copilotDir = Join-Path $env:USERPROFILE ".copilot\session-state"
                if (Test-Path -LiteralPath $copilotDir) {
                    $recentFile = Get-ChildItem -Path "$copilotDir\*\events.jsonl" -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1

                    if ($null -ne $recentFile) {
                        $lines = Get-Content -LiteralPath $recentFile.FullName -ErrorAction SilentlyContinue
                        $shutdown = $lines | Where-Object { $_ -match '"type":"session\.shutdown"' } | Select-Object -Last 1 | ConvertFrom-Json
                        if ($null -ne $shutdown -and $null -ne $shutdown.data -and $null -ne $shutdown.data.accountingSnapshot) {
                            $snap = $shutdown.data.accountingSnapshot
                            $model = if ($shutdown.data.currentModel) { [string]$shutdown.data.currentModel } else { "copilot" }
                            $inTokens = if ($snap.tokenDetails.input.tokenCount) { [int]$snap.tokenDetails.input.tokenCount } else { [int]$snap.usage.inputTokens }
                            $cacheRead = if ($snap.tokenDetails.cache_read.tokenCount) { [int]$snap.tokenDetails.cache_read.tokenCount } else { [int]$snap.usage.cacheReadTokens }
                            $cacheWrite = if ($snap.tokenDetails.cache_write.tokenCount) { [int]$snap.tokenDetails.cache_write.tokenCount } else { [int]$snap.usage.cacheWriteTokens }
                            $outTokens = if ($snap.tokenDetails.output.tokenCount) { [int]$snap.tokenDetails.output.tokenCount } else { [int]$snap.usage.outputTokens }
                            $credits = if ($snap.totalNanoAiu) { [Math]::Round([double]$snap.totalNanoAiu / 1000000000, 4) } else { 0 }
                            $duration = if ($snap.totalApiDurationMs) { [int]$snap.totalApiDurationMs } else { 0 }

                            Write-Host ""
                            Write-Host "===============================================================================" -ForegroundColor Cyan
                            Write-Host "  COPILOT ZERO-TRUST USAGE & TOKEN ACCOUNTING" -ForegroundColor Cyan
                            Write-Host "===============================================================================" -ForegroundColor Cyan
                            Write-Host "[*] Active Model       : $model"
                            Write-Host "[*] Input Tokens       : $inTokens (Cached: $cacheRead, Written: $cacheWrite)"
                            Write-Host "[*] Output Tokens      : $outTokens"
                            Write-Host "[*] AI Credits Used    : $credits"
                            Write-Host "[*] Total API Duration : $duration ms"
                            Write-Host "===============================================================================" -ForegroundColor Cyan
                            Write-Host ""

                            if (-not [string]::IsNullOrWhiteSpace($ServerUrl)) {
                                $finalAudit = @{
                                    event_id     = "ev-copilot-tokens-$SessionId"
                                    session_id   = $SessionId
                                    source       = "copilot"
                                    executable   = "token_accounting"
                                    arguments    = "In: $inTokens, Out: $outTokens, Credits: $credits"
                                    full_command = "Copilot Final Accounting ($model): $inTokens In, $outTokens Out, $credits Credits, ${duration}ms"
                                    decision     = "allow"
                                    reason       = "Copilot Final Token Accounting & AI Credit Audit"
                                    timestamp    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                                } | ConvertTo-Json -Compress
                                $curl = 'curl.exe'
                                $cArgs = @('-s', '--max-time', '2', '-X', 'POST', "$ServerUrl/api/v1/audit/ingest", '-H', 'Content-Type: application/json', '-d', $finalAudit)
                                & $curl @cArgs *> $null
                            }
                        }
                    }
                }
            } catch { }
        }

        if (-not [string]::IsNullOrWhiteSpace($BapEdgeBin) -and -not [string]::IsNullOrWhiteSpace($ServerUrl)) {
            & $BapEdgeBin session-end --server $ServerUrl --session-id $SessionId 2>$null
        }

        # Session teardown above uses the authenticated broker transport.        # Restore PATH and clean up Layer 3 shims
        if (-not [string]::IsNullOrWhiteSpace($origPath)) {
            $env:PATH = $origPath
        }
        if (-not [string]::IsNullOrWhiteSpace($ShimDir) -and (Test-Path -LiteralPath $ShimDir)) {
            Remove-Item -LiteralPath $ShimDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item Env:\BAP_MODE -ErrorAction SilentlyContinue
        Remove-Item Env:\BAP_AGENT_SANDBOX -ErrorAction SilentlyContinue
        Remove-Item Env:\BAP_IN_BROKER -ErrorAction SilentlyContinue

        # Restore scrubbed ambient credentials to host environment (BAP-535)
        if ($null -ne $scrubbedVars) {
            foreach ($k in $scrubbedVars.Keys) {
                [Environment]::SetEnvironmentVariable($k, $scrubbedVars[$k], 'Process')
            }
        }

        try {
            $teardownMutex = Acquire-BapMutex -Name $MutexName -TimeoutMs 5000
            try {
                if (Test-Path -LiteralPath $ManifestPath) {
                    $curRecord = Read-RecoveryRecord -ManifestPath $ManifestPath
                    if ($null -ne $curRecord) {
                        $surviving = @()
                        if ($curRecord.PSObject.Properties.Name -contains 'active_sessions' -and $null -ne $curRecord.active_sessions) {
                            foreach ($s in $curRecord.active_sessions) {
                                $spid = [int]($s.launcher_pid)
                                if ($spid -ne $PID -and $spid -gt 0) {
                                    $pr = Get-Process -Id $spid -ErrorAction SilentlyContinue
                                    if ($null -ne $pr -and -not $pr.HasExited) { $surviving += $s }
                                }
                            }
                        }

                        if ($surviving.Count -eq 0) {
                            # Last session: Kill watchdog and restore original files
                            if ($curRecord.PSObject.Properties.Name -contains 'watchdog_pid' -and $curRecord.watchdog_pid -gt 0) {
                                $wdPid = [int]($curRecord.watchdog_pid)
                                $wdPr = Get-Process -Id $wdPid -ErrorAction SilentlyContinue
                                if ($null -ne $wdPr -and -not $wdPr.HasExited) {
                                    Stop-Process -Id $wdPid -Force -ErrorAction SilentlyContinue
                                    try { $null = $wdPr.WaitForExit(3000) } catch { }
                                }
                            }
                            $curRecord.state = 'Cleaning'
                            try { Write-RecoveryRecord -Record $curRecord -ManifestPath $ManifestPath } catch { }
                            [void](Restore-BapSessionState -ManifestPath $ManifestPath -Reason 'last session teardown')
                        } else {
                            $curRecord.active_sessions = @($surviving)
                            try { Write-RecoveryRecord -Record $curRecord -ManifestPath $ManifestPath } catch { }
                            Write-Host "[*] Session '$SessionId' ended. $($surviving.Count) session(s) remain active in this workspace." -ForegroundColor Cyan
                        }
                    }
                }
            }
            finally {
                Release-BapMutex -Mutex $teardownMutex
            }
        }
        catch {
            Write-Warning "Teardown coordination notice: $($_.Exception.Message)"
        }

        # Restore environment
        Remove-Item Env:\BAP_SESSION_ID -ErrorAction SilentlyContinue
        Remove-Item Env:\LTD_SOURCE -ErrorAction SilentlyContinue
        $global:LASTEXITCODE = $ExitCode
        try { [System.Environment]::ExitCode = $ExitCode } catch { }
        try {
            if ($null -ne $Host -and $null -ne $Host.SetShouldExit) {
                $Host.SetShouldExit($ExitCode)
            }
        } catch { }
    }

    try { [System.Environment]::Exit($ExitCode) } catch { }
    exit $ExitCode
}


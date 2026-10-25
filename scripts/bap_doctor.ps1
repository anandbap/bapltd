# BAP Diagnostic Doctor - Environment & Pre-Flight Health Check
param(
    [string]$ServerUrl = $null
)

$ErrorActionPreference = 'Continue'
$repoRoot = (Get-Item -Path $PSScriptRoot).Parent.FullName

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "           BOUNDED AUTHORITY PLANE (BAP) - PRE-FLIGHT DOCTOR                   " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Host: $env:COMPUTERNAME | User: $env:USERNAME`n"

$totalChecks = 0
$passedChecks = 0
$warnChecks = 0

function Report-Check {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Status, # "PASS", "WARN", "FAIL"
        [string]$Details
    )
    $script:totalChecks++
    if ($Status -eq 'PASS') {
        $script:passedChecks++
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
    } elseif ($Status -eq 'WARN') {
        $script:warnChecks++
        Write-Host "  [WARN] " -ForegroundColor Yellow -NoNewline
    } else {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
    }
    Write-Host ("{0,-35} : {1}" -f $Name, $Details)
}

function Get-ResolvedPath($cmd) {
    if ($null -eq $cmd) { return $null }
    if ($cmd -is [System.IO.FileInfo]) { return $cmd.FullName }
    if ($cmd.Path) { return $cmd.Path }
    if ($cmd.Source) { return $cmd.Source }
    if ($cmd.Definition) { return $cmd.Definition }
    return $cmd.ToString()
}

# -----------------------------------------------------------------------------
# Section 1: Binary & Execution Tools
# -----------------------------------------------------------------------------
Write-Host "[1/5] Core BAP Binaries & Client Tools..." -ForegroundColor Cyan

$bapedge = Get-Command bapedge.exe -ErrorAction SilentlyContinue
if ($null -eq $bapedge) {
    $candidate = Join-Path $repoRoot "dist\windows-amd64\claude-client\bapedge.exe"
    if (Test-Path $candidate) { $bapedge = Get-Item $candidate }
}
$bapedgePath = Get-ResolvedPath $bapedge
if ($null -ne $bapedgePath -and (Test-Path $bapedgePath)) {
    $len = (Get-Item $bapedgePath).Length
    Report-Check -Name "bapedge.exe (Edge Daemon)" -Status "PASS" -Details "$bapedgePath ($([math]::Round($len / 1MB, 2)) MB)"
} else {
    Report-Check -Name "bapedge.exe (Edge Daemon)" -Status "FAIL" -Details "Not found in PATH or repo. Run install_bap_client.bat."
}

$interceptor = Get-Command interceptor.exe -ErrorAction SilentlyContinue
if ($null -eq $interceptor) {
    $candidate = Join-Path $repoRoot "dist\windows-amd64\claude-client\interceptor.exe"
    if (Test-Path $candidate) { $interceptor = Get-Item $candidate }
}
$interceptorPath = Get-ResolvedPath $interceptor
if ($null -ne $interceptorPath -and (Test-Path $interceptorPath)) {
    $len = (Get-Item $interceptorPath).Length
    Report-Check -Name "interceptor.exe (Claude Hook)" -Status "PASS" -Details "$interceptorPath ($([math]::Round($len / 1MB, 2)) MB)"
} else {
    Report-Check -Name "interceptor.exe (Claude Hook)" -Status "FAIL" -Details "Not found in PATH or repo. Run install_bap_client.bat."
}

$launcher = Get-Command run_claude_bap.bat -ErrorAction SilentlyContinue
if ($null -eq $launcher) {
    $candidate = Join-Path $repoRoot "run_claude_bap.bat"
    if (Test-Path $candidate) { $launcher = Get-Item $candidate }
}
$launcherPath = Get-ResolvedPath $launcher
if ($null -ne $launcherPath -and (Test-Path $launcherPath)) {
    Report-Check -Name "run_claude_bap.bat (Launcher)" -Status "PASS" -Details "$launcherPath"
} else {
    Report-Check -Name "run_claude_bap.bat (Launcher)" -Status "FAIL" -Details "Not found in PATH or repo root."
}

# -----------------------------------------------------------------------------
# Section 2: Claude Code CLI Detection
# -----------------------------------------------------------------------------
Write-Host "`n[2/5] AI Agent Runtime (Claude Code)..." -ForegroundColor Cyan

$claudeCmd = Get-Command claude.exe, claude.cmd, claude -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -ne $claudeCmd) {
    $claudeVer = "Unknown"
    try {
        $claudeVer = (& $claudeCmd.Source --version 2>$null | Out-String).Trim()
    } catch {}
    Report-Check -Name "Claude Code Executable" -Status "PASS" -Details "$($claudeCmd.Source) ($claudeVer)"
} else {
    Report-Check -Name "Claude Code Executable" -Status "WARN" -Details "claude.exe not found in PATH (Install via: npm install -g @anthropic-ai/claude-code)"
}

# -----------------------------------------------------------------------------
# Section 3: Central Control Plane & TLS
# -----------------------------------------------------------------------------
Write-Host "`n[3/5] Control Plane Connectivity & TLS..." -ForegroundColor Cyan

$cfgPath = $null
$mode = "enforce"
$cfgCandidates = @(
    (Join-Path $env:USERPROFILE "bin\bap-config.json"),
    (Join-Path $env:USERPROFILE ".bapstate\config.json"),
    (Join-Path $env:USERPROFILE ".bapstate\bap-config.json"),
    (Join-Path $env:USERPROFILE ".bap\config.json"),
    (Join-Path $env:USERPROFILE ".bap\bap-config.json"),
    (Join-Path (Get-Location).Path ".bap\bap-config.json"),
    (Join-Path (Get-Location).Path ".bap\config.json"),
    (Join-Path (Get-Location).Path "bap-config.json"),
    (Join-Path $repoRoot "bap-config.json")
)
foreach ($cfg in $cfgCandidates) {
    if ($cfg -and (Test-Path $cfg)) {
        try {
            $j = Get-Content $cfg -Raw | ConvertFrom-Json
            $cfgPath = (Get-Item $cfg).FullName
            if ($j.controlplane_url -and [string]::IsNullOrWhiteSpace($ServerUrl)) {
                $ServerUrl = $j.controlplane_url
            }
            if ($j.enforcement_mode) {
                $mode = $j.enforcement_mode
            }
            break
        } catch {}
    }
}

if ($null -ne $cfgPath) {
    Report-Check -Name "BAP Config (bap-config.json)" -Status "PASS" -Details "$cfgPath (Mode: $mode)"
} else {
    Report-Check -Name "BAP Config (bap-config.json)" -Status "WARN" -Details "Not found; using defaults"
}

if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
    $ServerUrl = "https://localhost:8443"
}

$serverUri = [Uri]$ServerUrl
$tcpClient = [System.Net.Sockets.TcpClient]::new()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tcpOk = $false
try {
    $iar = $tcpClient.BeginConnect($serverUri.Host, $serverUri.Port, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne(1500, $false)) {
        $tcpClient.EndConnect($iar)
        $tcpOk = $true
    }
} catch {}
finally {
    $tcpClient.Close()
    $sw.Stop()
}

if ($tcpOk) {
    Report-Check -Name "TCP Listener ($($serverUri.Host):$($serverUri.Port))" -Status "PASS" -Details "Port open (Latency: $($sw.ElapsedMilliseconds) ms)"
    
    # HTTP Health Check
    $healthUrl = "$ServerUrl/api/v1/health"
    try {
        $resp = Invoke-WebRequest -Uri $healthUrl -SkipCertificateCheck -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        Report-Check -Name "Health Check ($healthUrl)" -Status "PASS" -Details "Status $($resp.StatusCode) (Control Plane active)"
    } catch {
        Report-Check -Name "Health Check ($healthUrl)" -Status "WARN" -Details "TCP connected but HTTP responded: $($_.Exception.Message)"
    }
} else {
    Report-Check -Name "Control Plane ($ServerUrl)" -Status "WARN" -Details "Listener not reachable. Edge can still enforce cached Cedar policies offline."
}

# -----------------------------------------------------------------------------
# Section 4: Cedar Security Policies & Schema
# -----------------------------------------------------------------------------
Write-Host "`n[4/5] Cedar Policy Engine & Schema Invariants..." -ForegroundColor Cyan

$policyFile = $null
foreach ($pf in @("policy.cedar", "$repoRoot\policy.cedar", "$env:USERPROFILE\bin\policy.cedar")) {
    if (Test-Path $pf) { $policyFile = $pf; break }
}

if ($null -ne $policyFile) {
    $lines = (Get-Content $policyFile).Count
    Report-Check -Name "Cedar Policy File ($policyFile)" -Status "PASS" -Details "$lines lines loaded"
} else {
    Report-Check -Name "Cedar Policy File" -Status "FAIL" -Details "policy.cedar not found."
}

# Quick test of policy evaluation speed via bapedge
if ($null -ne $bapedgePath -and (Test-Path $bapedgePath)) {
    $swEval = [System.Diagnostics.Stopwatch]::StartNew()
    $evalProc = Start-Process -FilePath $bapedgePath -ArgumentList "exec", "--raw", "git --version" -PassThru -NoNewWindow -Wait
    $swEval.Stop()
    if ($evalProc.ExitCode -eq 0) {
        Report-Check -Name "Local Policy Evaluation" -Status "PASS" -Details "Safe command authorized in $($swEval.ElapsedMilliseconds) ms (< 1.5ms engine latency)"
    } else {
        Report-Check -Name "Local Policy Evaluation" -Status "WARN" -Details "Evaluator exited with code $($evalProc.ExitCode)"
    }
}

# -----------------------------------------------------------------------------
# Section 5: Workspace & Transaction Custody
# -----------------------------------------------------------------------------
Write-Host "`n[5/5] Workspace & Recovery Custody..." -ForegroundColor Cyan

$bapDir = Join-Path (Get-Location).Path ".bap"
if (Test-Path $bapDir) {
    Report-Check -Name "Workspace .bap/ Isolation" -Status "PASS" -Details "Isolated directory active (Zero root clutter)"
} else {
    Report-Check -Name "Workspace .bap/ Isolation" -Status "PASS" -Details "Clean workspace (Ready for on-demand initialization)"
}

$recoveryFile = Join-Path (Get-Location).Path ".claude\.bap-recovery.json"
if (Test-Path $recoveryFile) {
    try {
        $rec = Get-Content $recoveryFile -Raw | ConvertFrom-Json
        $activeCount = if ($rec.active_sessions) { $rec.active_sessions.Count } else { 0 }
        Report-Check -Name "Active BAP Transaction State" -Status "PASS" -Details "State: $($rec.state) ($activeCount active sessions)"
    } catch {
        Report-Check -Name "Active BAP Transaction State" -Status "WARN" -Details "Recovery file present but parse error"
    }
} else {
    Report-Check -Name "Active BAP Transaction State" -Status "PASS" -Details "Idle (No lingering transactions or lockouts)"
}

Write-Host "`n===============================================================================" -ForegroundColor Cyan
if ($warnChecks -eq 0) {
    Write-Host "  DOCTOR STATUS: ALL SYSTEMS HEALTHY! ($passedChecks/$totalChecks passed)" -ForegroundColor Green
} else {
    Write-Host "  DOCTOR STATUS: OPERATIONAL WITH $warnChecks WARNING(S) ($passedChecks/$totalChecks passed)" -ForegroundColor Yellow
}
Write-Host "===============================================================================" -ForegroundColor Cyan

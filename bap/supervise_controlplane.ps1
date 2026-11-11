# =============================================================================
# BAP Control Plane Process Supervisor (High-Availability Auto-Restart Daemon)
# =============================================================================
# Continuously monitors bapcontrolplane.exe. If the server crashes or is killed
# in Task Manager, the supervisor automatically respawns it within 1 second.
# =============================================================================

[CmdletBinding()]
param (
    [int]$Port = 8443,
    [switch]$Http,
    [string]$TrustDomain = "bap.internal",
    [int]$TTL = 30
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path

# Resolve Control Plane binary
$candidates = @(
    (Join-Path $repoRoot "dist\windows-amd64\controlplane\bapcontrolplane.exe"),
    (Join-Path $repoRoot "dist\windows-amd64\bapcontrolplane.exe"),
    (Join-Path $repoRoot "bapcontrolplane.exe"),
    (Join-Path $repoRoot "bap-controlplane\bapcontrolplane.exe")
)

$binPath = $null
foreach ($c in $candidates) {
    if (Test-Path $c) {
        $binPath = $c
        break
    }
}

if ($null -eq $binPath) {
    Write-Error "Could not find bapcontrolplane.exe. Run build_binaries.bat first."
    exit 1
}

# Resolve config port and scheme from bap-config.json if not explicitly passed
$configPath = Join-Path $repoRoot "bap-config.json"
if (Test-Path $configPath) {
    try {
        $cfg = Get-Content -Raw $configPath | ConvertFrom-Json
        if ($cfg.controlplane_url) {
            $u = [System.Uri]$cfg.controlplane_url
            if ($PSBoundParameters.ContainsKey('Port') -eq $false -and $u.Port -gt 0) {
                $Port = $u.Port
            }
            if ($PSBoundParameters.ContainsKey('Http') -eq $false -and $u.Scheme -eq "http") {
                $Http = $true
            }
        }
    } catch {
        # Fall back to parameters
    }
}

$argsList = @("-port", $Port, "-ttl", $TTL, "-trust-domain", $TrustDomain)
if (-not $Http) {
    $argsList += "-https"
}
$argsList += "-demo-mode"

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "          BAP CONTROL PLANE - HIGH-AVAILABILITY SUPERVISOR                     " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "[*] Binary       : $binPath"
Write-Host "[*] Port         : $Port"
Write-Host "[*] Scheme       : $(if ($Http) { 'HTTP' } else { 'HTTPS (TLS Auto)' })"
Write-Host "[*] Supervisor   : Active (Press Ctrl+C to stop supervisor and server)"
Write-Host "===============================================================================" -ForegroundColor Cyan

$pidFile = Join-Path $repoRoot ".bap-controlplane-supervisor.pid"
Set-Content -Path $pidFile -Value $PID -Force

$global:ServerProc = $null

# Register graceful exit handler for Ctrl+C
try { [Console]::TreatControlCAsInput = $false } catch {}
Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action {
    if (Test-Path $pidFile) { Remove-Item -Force $pidFile -ErrorAction SilentlyContinue }
    if ($global:ServerProc -and -not $global:ServerProc.HasExited) {
        Write-Host "`n[*] Terminating supervised bapcontrolplane..." -ForegroundColor Yellow
        Stop-Process -Id $global:ServerProc.Id -Force -ErrorAction SilentlyContinue
    }
} | Out-Null

$restartCount = 0

while ($true) {
    Write-Host "[+] Spawning bapcontrolplane.exe (Attempt #$($restartCount + 1))..." -ForegroundColor Green
    
    $global:ServerProc = Start-Process `
        -FilePath $binPath `
        -ArgumentList $argsList `
        -PassThru `
        -NoNewWindow

    Write-Host "[+] bapcontrolplane running with PID $($global:ServerProc.Id)." -ForegroundColor Green
    
    # Wait for the process to exit or be killed in Task Manager
    $global:ServerProc.WaitForExit()
    $exitCode = $global:ServerProc.ExitCode

    Write-Host "`n[!] WARNING: bapcontrolplane (PID $($global:ServerProc.Id)) exited or was killed! Exit code: $exitCode" -ForegroundColor Red
    $restartCount++
    Write-Host "[*] Auto-Restart Supervisor: Respawning in 1 second..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}


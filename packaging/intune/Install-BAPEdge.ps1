<#
.SYNOPSIS
    Microsoft Intune Win32 App Deployment Script for BAP Edge Daemon
.DESCRIPTION
    Installs bapedge.exe into %ProgramFiles%\BAP, provisions default configurations,
    registers the system PATH, and initiates the background daemon.
#>
param(
    [string]$InstallDir = "$env:ProgramFiles\BAP",
    [string]$ControlPlaneURL = "https://controlplane.company.internal:8443",
    [string]$TrustDomain = "bap.internal"
)

$ErrorActionPreference = "Stop"
Write-Output ">>> Starting BAP Edge deployment..."

# Test if ProgramFiles target is writable without elevation; fallback to user home
$useUserScope = $false
try {
    if (!(Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction Stop | Out-Null
    }
    $testFile = Join-Path $InstallDir ".perm_test"
    Set-Content -Path $testFile -Value "ok" -ErrorAction Stop
    Remove-Item -Path $testFile -Force -ErrorAction Stop
} catch {
    Write-Output ">>> $InstallDir requires administrative privileges. Defaulting to user home permanent path."
    $InstallDir = Join-Path $env:USERPROFILE ".bap"
    $useUserScope = $true
    if (!(Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
}

$binDir = Join-Path $InstallDir "bin"
if (!(Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Copy BAP binaries and configurations
$binaries = @("bapedge.exe", "interceptor.exe", "bapmcp.exe", "bapcontrolplane.exe", "bapgateway.exe")
foreach ($bin in $binaries) {
    if (Test-Path (Join-Path $scriptDir $bin)) {
        Copy-Item (Join-Path $scriptDir $bin) -Destination $binDir -Force
        Copy-Item (Join-Path $scriptDir $bin) -Destination $InstallDir -Force
    }
}
if (Test-Path (Join-Path $scriptDir "cchook\interceptor.exe")) {
    Copy-Item (Join-Path $scriptDir "cchook\interceptor.exe") -Destination (Join-Path $binDir "interceptor.exe") -Force
}
if (Test-Path (Join-Path $scriptDir "bap-config.json")) {
    Copy-Item (Join-Path $scriptDir "bap-config.json") -Destination $InstallDir -Force
}
if (Test-Path (Join-Path $scriptDir "policy.cedar")) {
    Copy-Item (Join-Path $scriptDir "policy.cedar") -Destination $InstallDir -Force
}
if (Test-Path (Join-Path $scriptDir "schema.json")) {
    Copy-Item (Join-Path $scriptDir "schema.json") -Destination $InstallDir -Force
}

# Add to PATH (Machine if elevated, User if non-elevated)
$targetScope = if ($useUserScope) { [System.EnvironmentVariableTarget]::User } else { [System.EnvironmentVariableTarget]::Machine }
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", $targetScope)
$pathsToAdd = @($binDir, $InstallDir)
$updatedPath = $currentPath
foreach ($p in $pathsToAdd) {
    if ($updatedPath -notlike "*$p*") {
        $updatedPath = if ([string]::IsNullOrWhiteSpace($updatedPath)) { $p } else { "$p;$updatedPath" }
        Write-Output ">>> Appended $p to $(if ($useUserScope) { 'User' } else { 'System' }) PATH."
    }
}
if ($updatedPath -ne $currentPath) {
    [System.Environment]::SetEnvironmentVariable("Path", $updatedPath, $targetScope)
}

# Register Windows Service / Task Scheduler for background liveness
$action = New-ScheduledTaskAction -Execute "$binDir\bapedge.exe" -Argument "watch --config `"$InstallDir\bap-config.json`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

try {
    if ($useUserScope) {
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
        Register-ScheduledTask -TaskName "BAPEdgeDaemon" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    } else {
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "BAPEdgeDaemon" -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings -Force | Out-Null
    }
    Start-ScheduledTask -TaskName "BAPEdgeDaemon" -ErrorAction SilentlyContinue
    Write-Output ">>> Registered and started BAPEdgeDaemon scheduled task."
} catch {
    Write-Warning "Could not register scheduled task: $_"
}

Write-Output ">>> BAP Edge deployed successfully."
exit 0

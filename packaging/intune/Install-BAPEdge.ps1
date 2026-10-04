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
Write-Output ">>> Starting BAP Edge deployment via Microsoft Intune..."

# Create installation directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Copy BAP binaries and configurations
Copy-Item (Join-Path $scriptDir "bapedge.exe") -Destination $InstallDir -Force
if (Test-Path (Join-Path $scriptDir "bap-config.json")) {
    Copy-Item (Join-Path $scriptDir "bap-config.json") -Destination $InstallDir -Force
}
if (Test-Path (Join-Path $scriptDir "policy.cedar")) {
    Copy-Item (Join-Path $scriptDir "policy.cedar") -Destination $InstallDir -Force
}
if (Test-Path (Join-Path $scriptDir "schema.json")) {
    Copy-Item (Join-Path $scriptDir "schema.json") -Destination $InstallDir -Force
}

# Add to System PATH if not present
$machinePath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
if ($machinePath -notlike "*$InstallDir*") {
    $newPath = "$machinePath;$InstallDir"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
    Write-Output ">>> Appended $InstallDir to System PATH."
}

# Register Windows Service / Task Scheduler for background liveness
$action = New-ScheduledTaskAction -Execute "$InstallDir\bapedge.exe" -Argument "watch --config `"$InstallDir\bap-config.json`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

try {
    Register-ScheduledTask -TaskName "BAPEdgeDaemon" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName "BAPEdgeDaemon" -ErrorAction SilentlyContinue
    Write-Output ">>> Registered and started BAPEdgeDaemon scheduled task."
} catch {
    Write-Warning "Could not register scheduled task: $_"
}

Write-Output ">>> BAP Edge deployed successfully."
exit 0

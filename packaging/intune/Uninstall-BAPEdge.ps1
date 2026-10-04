<#
.SYNOPSIS
    Microsoft Intune Uninstallation Script for BAP Edge
#>
$ErrorActionPreference = "SilentlyContinue"
$InstallDir = "$env:ProgramFiles\BAP"

# Stop and unregister scheduled task
Stop-ScheduledTask -TaskName "BAPEdgeDaemon"
Unregister-ScheduledTask -TaskName "BAPEdgeDaemon" -Confirm:$false

# Remove from system PATH
$machinePath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
if ($machinePath -like "*$InstallDir*") {
    $newPath = ($machinePath.Split(';') | Where-Object { $_ -ne $InstallDir -and $_ -ne "" }) -join ';'
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, [System.EnvironmentVariableTarget]::Machine)
}

# Remove folder
if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
}

Write-Output "BAP Edge uninstalled successfully."
exit 0

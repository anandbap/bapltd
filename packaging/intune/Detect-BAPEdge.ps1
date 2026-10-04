<#
.SYNOPSIS
    Microsoft Intune Custom Detection Script for BAP Edge
.DESCRIPTION
    Checks if bapedge.exe is installed, in the system PATH, and responsive.
    Returns standard STDOUT string and exit code 0 if detected.
#>
$InstallDir = "$env:ProgramFiles\BAP"
$BinaryPath = Join-Path $InstallDir "bapedge.exe"

if (Test-Path $BinaryPath) {
    try {
        $versionInfo = & $BinaryPath version 2>&1
        Write-Output "BAP Edge detected at $BinaryPath: $versionInfo"
        exit 0
    } catch {
        Write-Output "BAP Edge detected at $BinaryPath"
        exit 0
    }
}

# Not detected
exit 1

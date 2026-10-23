<#
.SYNOPSIS
    Bounded Authority Plane (BAP) - Executive CIO Demonstration Launcher (PowerShell)
.DESCRIPTION
    Launches the BAP Agent Watch V3 Executive CIO Demonstration or Workforce scenarios.
.PARAMETER Mode
    Demo scenario to execute: 'v3' (default), 'workforce', or 'remote'
.PARAMETER NoBrowser
    Do not automatically launch web browser
.PARAMETER Url
    Custom Control Plane URL
.PARAMETER Duration
    Duration in seconds to run live simulation (default: interactive prompt)
.PARAMETER NoPrompt
    Run baseline checks non-interactively and exit cleanly
#>
[CmdletBinding()]
param(
    [ValidateSet('v3', 'workforce', 'remote')]
    [string]$Mode = 'v3',
    [switch]$NoBrowser,
    [string]$Url = '',
    [int]$Duration = 0,
    [switch]$NoPrompt,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host "=========================================================================================================" -ForegroundColor Cyan
Write-Host "              BOUNDED AUTHORITY PLANE (BAP) - EXECUTIVE CIO DEMONSTRATION LAUNCHER" -ForegroundColor Cyan
Write-Host "                      Real-Time Multi-Agent Fleet Governance, Proof & HITL Control" -ForegroundColor Cyan
Write-Host "=========================================================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Python
try {
    $pyVer = & python --version 2>&1
    Write-Host "[+] Using Python: $pyVer" -ForegroundColor Green
} catch {
    Write-Error "Python 3 is not found in PATH. Please install Python 3.8+ to run this demo."
    exit 1
}

$pyArgs = @()
if ($NoBrowser) { $pyArgs += '--no-browser' }
if ($Url) { $pyArgs += @('--url', $Url) }
if ($Duration -gt 0) { $pyArgs += @('--duration', $Duration.ToString()) }
if ($NoPrompt) { $pyArgs += '--no-prompt' }
if ($RemainingArgs) { $pyArgs += $RemainingArgs }

switch ($Mode.ToLower()) {
    'workforce' {
        & python demo_cio_workforce.py @pyArgs
    }
    'remote' {
        & python demo_remote_cio.py @pyArgs
    }
    default {
        & python demo_v3_cio.py @pyArgs
    }
}

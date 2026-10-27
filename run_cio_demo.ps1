<#
.SYNOPSIS
    Bounded Authority Plane (BAP) - Executive CIO Demonstration Launcher (PowerShell)
.DESCRIPTION
    Launches the BAP Agent Watch V3 Executive CIO Demonstration or Workforce scenarios.
.PARAMETER Mode
    Demo scenario to execute: 'v3' (default), 'workforce', or 'remote'
.PARAMETER Remote
    Target the remote Render control plane (https://bap-controlplane.onrender.com)
.PARAMETER Local
    Force local embedded control plane (http://localhost:8080)
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
    [switch]$Remote,
    [switch]$Local,
    [switch]$NoBrowser,
    [string]$Url = '',
    [int]$Duration = 0,
    [switch]$NoPrompt,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

Set-Location $PSScriptRoot

Write-Host "=========================================================================================================" -ForegroundColor Cyan
Write-Host "              BOUNDED AUTHORITY PLANE (BAP) - EXECUTIVE CIO DEMONSTRATION LAUNCHER" -ForegroundColor Cyan
Write-Host "                      Real-Time Multi-Agent Fleet Governance, Proof & HITL Control" -ForegroundColor Cyan
Write-Host "=========================================================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Python
$pyBin = "python"
$pyCheck = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCheck) {
    foreach ($cand in @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "$env:ProgramFiles\Python312\python.exe", "C:\Python312\python.exe")) {
        if (Test-Path $cand) {
            $pyBin = $cand
            break
        }
    }
}

$pyArgs = @()
if ($Remote -or ($Mode.ToLower() -eq 'remote')) { $pyArgs += '--remote' }
if ($Local) { $pyArgs += '--local' }
if ($NoBrowser) { $pyArgs += '--no-browser' }
if ($Url) { $pyArgs += @('--url', $Url) }
if ($Duration -gt 0) { $pyArgs += @('--duration', $Duration.ToString()) }
if ($NoPrompt) { $pyArgs += '--no-prompt' }
if ($RemainingArgs) { $pyArgs += $RemainingArgs }

switch ($Mode.ToLower()) {
    'workforce' {
        & $pyBin demo_cio_workforce.py @pyArgs
    }
    default {
        & $pyBin demo_v3_cio.py @pyArgs
    }
}

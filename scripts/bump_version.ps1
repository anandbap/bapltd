<#
.SYNOPSIS
    scripts\bump_version.ps1 — BAP Semantic Version Bumper for PowerShell
.DESCRIPTION
    Bumps semantic versions across all BAP components (Go, Python, WiX, Jamf, Deb).
.EXAMPLE
    .\scripts\bump_version.ps1 -Minor
    .\scripts\bump_version.ps1 -Patch
    .\scripts\bump_version.ps1 -Major
    .\scripts\bump_version.ps1 -Set "1.2.0"
    .\scripts\bump_version.ps1 -Minor -DryRun
    .\scripts\bump_version.ps1 -Minor -Rebuild
#>
param(
    [switch]$Minor,
    [switch]$Patch,
    [switch]$Major,
    [string]$Set,
    [switch]$Current,
    [switch]$DryRun,
    [switch]$Rebuild
)

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scriptPath = Join-Path $rootDir "bump_version.py"

$argsList = @()
if ($Current) { $argsList += "--current" }
elseif ($Set) { $argsList += "--set", $Set }
elseif ($Minor) { $argsList += "--minor" }
elseif ($Patch) { $argsList += "--patch" }
elseif ($Major) { $argsList += "--major" }
else {
    Write-Host "Usage: .\scripts\bump_version.ps1 [-Minor | -Patch | -Major | -Set <version>] [-DryRun] [-Rebuild]" -ForegroundColor Yellow
    exit 1
}

if ($DryRun) { $argsList += "--dry-run" }
if ($Rebuild) { $argsList += "--rebuild" }

& python $scriptPath @argsList

# ==============================================================================
# Bounded Authority Plane (BAP) - Stale Asset & UI Copy Verification Script
# ==============================================================================
# Verifies that all copies of web assets (inspector.html, inspector_v2.html, etc.)
# across all build targets, dist packages, and internal directories exactly match
# the root source of truth.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check_stale_copies.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check_stale_copies.ps1 -Fix
# ==============================================================================

param(
    [switch]$Fix,
    [string[]]$TrackedFiles = @("inspector.html", "inspector_v2.html", "policy.cedar", "schema.json")
)

Import-Module Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue

function Get-SHA256Hash($path) {
    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) {
        return (Get-FileHash $path -Algorithm SHA256).Hash
    }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash($bytes)
    return [System.BitConverter]::ToString($hash).Replace("-", "").ToUpper()
}

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Get-Item (Join-Path $scriptDir "..")).FullName

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  BAP ASSET INTEGRITY AUDIT: Checking for Stale Copies across Fleet" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan

$totalFilesChecked = 0
$totalCopiesVerified = 0
$staleCopiesFound = 0
$fixedCount = 0

# Folders to skip during recursive search
$excludedFolders = @(".git", ".gemini", "node_modules", ".system_generated", "scratch", ".claude")

foreach ($filename in $TrackedFiles) {
    $rootSource = Join-Path $rootDir $filename
    if (!(Test-Path $rootSource)) {
        Write-Host "[-] Skipping $($filename): Root source file not found at $rootSource" -ForegroundColor Yellow
        continue
    }

    $totalFilesChecked++
    $sourceHash = Get-SHA256Hash $rootSource
    $sourceSize = (Get-Item $rootSource).Length
    $shortHash = $sourceHash.Substring(0, 12).ToLower()

    Write-Host "`n[*] Auditing asset: $filename" -ForegroundColor White
    Write-Host "    Source of Truth : $rootSource" -ForegroundColor DarkGray
    Write-Host "    Expected SHA-256: $shortHash... ($sourceSize bytes)" -ForegroundColor DarkGray

    # Recursively find all copies of this file
    $allCopies = Get-ChildItem -Path $rootDir -Filter $filename -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
        $p = $_.FullName
        $skip = $false
        foreach ($ex in $excludedFolders) {
            if ($p -match [regex]::Escape([System.IO.Path]::DirectorySeparatorChar + $ex + [System.IO.Path]::DirectorySeparatorChar)) {
                $skip = $true
                break
            }
        }
        -not $skip
    }

    $copiesInSync = 0
    foreach ($copy in $allCopies) {
        $copyPath = $copy.FullName
        $copyHash = Get-SHA256Hash $copyPath
        $relPath = $copyPath.Replace($rootDir, "").TrimStart("\/")

        if ($copyHash -eq $sourceHash) {
            $copiesInSync++
            $totalCopiesVerified++
        } else {
            $staleCopiesFound++
            $foundShort = $copyHash.Substring(0, 12).ToLower()
            Write-Host "  [STALE] $relPath (Found: $foundShort..., Expected: $shortHash)" -ForegroundColor Red

            if ($Fix) {
                Copy-Item -Path $rootSource -Destination $copyPath -Force
                Write-Host "          --> AUTO-REPAIRED: Overwritten with root source of truth." -ForegroundColor Green
                $fixedCount++
            }
        }
    }

    Write-Host "    Status: $copiesInSync of $($allCopies.Count) copies in exact sync." -ForegroundColor Green
}

Write-Host "`n===============================================================================" -ForegroundColor Cyan
if ($staleCopiesFound -eq 0) {
    Write-Host "  [VERIFIED] ALL COPIES ARE IN SYNC! No stale copies found ($totalCopiesVerified verified)." -ForegroundColor Green
    Write-Host "===============================================================================" -ForegroundColor Cyan
    exit 0
} elseif ($Fix -and ($fixedCount -eq $staleCopiesFound)) {
    Write-Host "  [FIXED] Repaired $fixedCount stale copies. All copies now match root source." -ForegroundColor Green
    Write-Host "===============================================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "  [FAIL] Found $staleCopiesFound STALE copies! Run with -Fix to synchronize automatically." -ForegroundColor Red
    Write-Host "===============================================================================" -ForegroundColor Cyan
    exit 1
}

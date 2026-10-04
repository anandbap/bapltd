<#
.SYNOPSIS
    Builds Windows Installer (.msi) for BAP Edge
#>
param(
    [string]$Version = "1.0.0",
    [string]$DistDir = "dist\windows-amd64",
    [string]$OutputFile = "dist\bapedge-windows-amd64-1.0.0.msi"
)

$rootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$wixFile = Join-Path (Join-Path $rootDir "packaging\intune") "bapedge.wxs"
$outMsi = Join-Path $rootDir $OutputFile

Write-Host ">>> Checking for WiX Toolset..." -ForegroundColor Cyan

# Check for wix.exe or candle/light
$wixCmd = Get-Command "wix" -ErrorAction SilentlyContinue
$candleCmd = Get-Command "candle" -ErrorAction SilentlyContinue
$lightCmd = Get-Command "light" -ErrorAction SilentlyContinue

if ($candleCmd -and $lightCmd) {
    Write-Host ">>> Compiling MSI with WiX v3..." -ForegroundColor Green
    $wixObj = [System.IO.Path]::ChangeExtension($wixFile, ".wixobj")
    & candle -out $wixObj $wixFile
    & light -out $outMsi $wixObj
    Remove-Item $wixObj -Force -ErrorAction SilentlyContinue
    Write-Host ">>> Built MSI: $outMsi" -ForegroundColor Green
} elseif ($wixCmd) {
    Write-Host ">>> Compiling MSI with WiX v4/v5..." -ForegroundColor Green
    & wix build $wixFile -o $outMsi
    Write-Host ">>> Built MSI: $outMsi" -ForegroundColor Green
} else {
    Write-Warning "WiX toolset not found on this host. Packaging ready-to-deploy Intune ZIP bundle instead."
    $intuneBundleDir = Join-Path $rootDir "dist\windows-amd64\intune-package"
    if (!(Test-Path $intuneBundleDir)) { New-Item -ItemType Directory -Path $intuneBundleDir -Force | Out-Null }
    
    Copy-Item (Join-Path $rootDir "$DistDir\bapedge.exe") -Destination $intuneBundleDir -Force
    Copy-Item (Join-Path $rootDir "bap-config.json") -Destination $intuneBundleDir -Force
    Copy-Item (Join-Path $rootDir "packaging\intune\Install-BAPEdge.ps1") -Destination $intuneBundleDir -Force
    Copy-Item (Join-Path $rootDir "packaging\intune\Uninstall-BAPEdge.ps1") -Destination $intuneBundleDir -Force
    Copy-Item (Join-Path $rootDir "packaging\intune\Detect-BAPEdge.ps1") -Destination $intuneBundleDir -Force
    Copy-Item (Join-Path $rootDir "packaging\intune\Intune-BAP-Policy.xml") -Destination $intuneBundleDir -Force
    
    $zipOut = [System.IO.Path]::ChangeExtension($outMsi, ".zip")
    Compress-Archive -Path "$intuneBundleDir\*" -DestinationPath $zipOut -Force
    Write-Host ">>> Generated Intune deployable archive: $zipOut" -ForegroundColor Green
}

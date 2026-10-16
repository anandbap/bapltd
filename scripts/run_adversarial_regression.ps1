# =============================================================================
# BAP Standing Adversarial Regression & Continuous Scanning Harness (BAP-536)
# =============================================================================
# Validates:
# 1. Indirect prompt injection attacks in repo files & skills
# 2. Header spoofing & unauthorized bypass probes against Gateway PEP
# 3. Same-domain multi-tenant exfiltration probes (GitHub orgs / S3 accounts)
# 4. Hook tampering, missing interceptor, and silent crash resistance
# 5. Continuous add-on scanner threat detection on installed skills
# =============================================================================

[CmdletBinding()]
param (
    [switch]$Json,
    [string]$FailOn = "high"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
Set-Location $repoRoot

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  [BAP-536] Standing Adversarial Regression & Continuous Scanner Suite" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  Workspace: $repoRoot"
Write-Host "  Fail-On:   $FailOn"
Write-Host "-------------------------------------------------------------------------------"

# Step 1: Run Continuous Add-on Threat Scanner on Workspace
Write-Host "[1/2] Executing Continuous Add-on & Skill Threat Scanner on workspace..." -ForegroundColor Yellow
$bapedge = Join-Path $repoRoot "dist\windows-amd64\bapedge.exe"
if (-not (Test-Path $bapedge)) {
    $bapedge = Join-Path $repoRoot "bapedge.exe"
}

$scanArgs = @("scan", $repoRoot, "--fail-on", $FailOn)
if ($Json) { $scanArgs += "--json" }

& $bapedge $scanArgs
$scanExit = $LASTEXITCODE

if ($scanExit -ne 0) {
    Write-Host "[-] Add-on threat scanner detected policy violations exceeding threshold ($FailOn)!" -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] Workspace skills and manifests passed continuous security scan." -ForegroundColor Green

# Step 2: Run Automated Adversarial Regression Suite
Write-Host ""
Write-Host "[2/2] Running automated adversarial regression matrix..." -ForegroundColor Yellow
& python -m unittest tests.test_bap_536_adversarial_scanner
$regExit = $LASTEXITCODE

if ($regExit -ne 0) {
    Write-Host "[-] Adversarial regression suite failed! Regression detected." -ForegroundColor Red
    exit 1
}
Write-Host "[PASS] All adversarial regression matrix checks passed (100% fail-closed)." -ForegroundColor Green

Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  [PASS] [BAP-536] Adversarial Regression & Add-on Audit Verified Successfully!" -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Cyan
exit 0

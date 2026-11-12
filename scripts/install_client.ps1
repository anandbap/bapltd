# BAP Client One-Click Developer Installer
param(
    [string]$TargetDir = (Join-Path $env:USERPROFILE "bin"),
    [switch]$Force = $false,
    [switch]$Debug = $false
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Get-Item -Path $PSScriptRoot).Parent.FullName

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "      BAP CLIENT - ONE-CLICK DEVELOPER ONBOARDING INSTALLER                    " -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "[*] Target Installation Directory: $TargetDir"

if (-not (Test-Path -LiteralPath $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    Write-Host "[+] Created directory: $TargetDir" -ForegroundColor Green
}

$sourceDir = Join-Path $repoRoot "dist\windows-amd64\claude-client"
if (-not (Test-Path -LiteralPath $sourceDir)) {
    $sourceDir = $repoRoot
}

$clientFiles = @(
    "bap.exe",
    "bapedge.exe",
    "interceptor.exe",
    "run_claude_bap.bat",
    "run_claude_bap.ps1",
    "bap-config.json",
    "policy.cedar",
    "schema.json"
)

$installedCount = 0
foreach ($f in $clientFiles) {
    $src = Join-Path $sourceDir $f
    if (-not (Test-Path -LiteralPath $src)) {
        $src = Join-Path $repoRoot $f
    }

    if (Test-Path -LiteralPath $src) {
        $dst = Join-Path $TargetDir $f
        Copy-Item -LiteralPath $src -Destination $dst -Force
        $size = (Get-Item -LiteralPath $dst).Length
        Write-Host ("  [+] Installed: {0,-22} ({1:N0} bytes)" -f $f, $size) -ForegroundColor Green
        $installedCount++
    } else {
        Write-Warning "Source file not found: $f"
    }
}

if ($Debug) {
    Write-Host "`n[*] Deploying Debugging & Diagnostic Utilities (-Debug active)..." -ForegroundColor Cyan
    $debugFiles = @(
        "review_session.ps1",
        "review_session.bat",
        "review_session.sh",
        "watch_session.ps1",
        "watch_session.bat",
        "watch_session.sh",
        "verify_sts_obo_exchange.py",
        "verify_sts.bat",
        "verify_sts.sh",
        "check_stale_copies.ps1",
        "check_stale_copies.bat",
        "check_stale_copies.sh",
        "run_claude_scenarios.ps1"
    )
    foreach ($df in $debugFiles) {
        $src = Join-Path (Join-Path $repoRoot "scripts") $df
        if (-not (Test-Path -LiteralPath $src)) {
            $src = Join-Path $repoRoot $df
        }
        if (Test-Path -LiteralPath $src) {
            $dst = Join-Path $TargetDir $df
            Copy-Item -LiteralPath $src -Destination $dst -Force
            $size = (Get-Item -LiteralPath $dst).Length
            Write-Host ("  [+] Installed Debug Tool: {0,-22} ({1:N0} bytes)" -f $df, $size) -ForegroundColor Green
            $installedCount++
        }
    }
} else {
    Write-Host "`n[*] Standard Install: Debugging scripts omitted by default. (Pass -Debug to deploy review/watch/sts/stale-check tools)" -ForegroundColor DarkGray
}

Write-Host "`n[*] Configuring Environment PATH..."
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ([string]::IsNullOrWhiteSpace($userPath)) {
    $userPath = ""
}

$pathParts = $userPath.Split(';') | ForEach-Object { $_.Trim().TrimEnd('\') } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
$targetNormalized = $TargetDir.Trim().TrimEnd('\')

if ($pathParts -contains $targetNormalized) {
    Write-Host "[+] User PATH already contains: $TargetDir" -ForegroundColor Green
} else {
    $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $TargetDir } else { "$userPath;$TargetDir" }
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    Write-Host "[+] Added to User PATH: $TargetDir" -ForegroundColor Green
    Write-Host "    (Changes will apply to all new terminal sessions)" -ForegroundColor Gray
}

# Update current session PATH so it can be used immediately
if ($env:PATH -notmatch [regex]::Escape($targetNormalized)) {
    $env:PATH = "$env:PATH;$TargetDir"
}

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "  INSTALLATION SUCCESSFUL! ($installedCount files deployed)                   " -ForegroundColor Green
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "You can now run Claude Code governed by BAP from ANY directory:"
Write-Host "  > run_claude_bap" -ForegroundColor Yellow
Write-Host "  > run_claude_bap --version" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Cyan

# BAP Zero-Trust User Profile Deployer
# =====================================
# Deploys ~/.bap/bap-profile.ps1 and updates user PowerShell $PROFILE

$bapDir = Join-Path $env:USERPROFILE ".bap"
if (-not (Test-Path -LiteralPath $bapDir)) {
    New-Item -ItemType Directory -Path $bapDir -Force | Out-Null
}

$targetProfilePs1 = Join-Path $bapDir "bap-profile.ps1"
$sourceProfilePs1 = Join-Path $PSScriptRoot "..\bap\bap-profile.ps1"
if (-not (Test-Path -LiteralPath $sourceProfilePs1)) {
    $sourceProfilePs1 = Join-Path (Get-Location).Path "bap\bap-profile.ps1"
}

Copy-Item -LiteralPath $sourceProfilePs1 -Destination $targetProfilePs1 -Force
Write-Host "[+] Deployed BAP auto-binding profile to: $targetProfilePs1" -ForegroundColor Green

$sourceLine = 'if (Test-Path "$env:USERPROFILE\.bap\bap-profile.ps1") { . "$env:USERPROFILE\.bap\bap-profile.ps1" }'

$docsFolder = [Environment]::GetFolderPath('MyDocuments')
$profileTargets = @(
    $PROFILE,
    (Join-Path $docsFolder 'PowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $docsFolder 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $env:USERPROFILE 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'),
    (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1')
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

foreach ($p in $profileTargets) {
    try {
        $pDir = Split-Path -Parent $p
        if (-not (Test-Path -LiteralPath $pDir)) {
            New-Item -ItemType Directory -Path $pDir -Force | Out-Null
        }
        $existing = if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw -ErrorAction SilentlyContinue } else { '' }
        if ($existing -notmatch 'bap-profile\.ps1') {
            Add-Content -LiteralPath $p -Value "`n# BAP Zero-Trust Agent Auto-Binding`n$sourceLine`n"
            Write-Host "[+] Configured auto-binding in: $p" -ForegroundColor Green
        } else {
            Write-Host "[OK] Auto-binding already configured in: $p" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "Could not update profile target $p : $($_.Exception.Message)"
    }
}

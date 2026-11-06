<#
.SYNOPSIS
    BAP Zero-Trust Session Reviewer & Performance Inspector
.DESCRIPTION
    Root forwarder for scripts/review_session.ps1.
#>

$scriptPath = Join-Path $PSScriptRoot "scripts\review_session.ps1"
if (-not (Test-Path -LiteralPath $scriptPath)) {
    $scriptPath = Join-Path (Get-Location) "scripts\review_session.ps1"
}

& $scriptPath @args
exit $LASTEXITCODE
